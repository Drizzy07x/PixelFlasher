#!/usr/bin/env python

# This file is part of PixelFlasher https://github.com/badabing2005/PixelFlasher
#
# Copyright (C) 2025 Badabing2005
# SPDX-FileCopyrightText: 2025 Badabing2005
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
# for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Also add information on how to contact you by electronic and paper mail.
#
# If your software can interact with users remotely through a computer network,
# you should also make sure that it provides a way for users to get its source.
# For example, if your program is a web application, its interface could
# display a "Source" link that leads users to an archive of the code. There are
# many ways you could offer source, and different solutions will be better for
# different programs; see section 13 for the specific requirements.
#
# You should also get your employer (if you work as a programmer) or school, if
# any, to sign a "copyright disclaimer" for the program, if necessary. For more
# information on this, and how to apply and follow the GNU AGPL, see
# <https://www.gnu.org/licenses/>.

import os

os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"

import sys
import tempfile
import traceback


def _run_cli_command(argv):
    """Handle low-risk CLI utilities without importing the wx UI.

    This keeps CI, diagnostics, and support collection working on systems
    that do not have wxPython or a display server installed.
    """
    cli_flags = {
        "--self-test",
        "--doctor",
        "--diagnostics",
        "--version",
        "-V",
        "--help",
        "-h",
    }
    pty_smoke_requested = any(
        arg == "--pty-smoke-report" or arg.startswith("--pty-smoke-report=")
        for arg in argv[1:]
    )
    legacy_raw_smoke_requested = any(
        arg == "--legacy-raw-smoke-report"
        or arg.startswith("--legacy-raw-smoke-report=")
        for arg in argv[1:]
    )
    if len(argv) <= 1 or not (
        any(arg in cli_flags for arg in argv[1:])
        or pty_smoke_requested
        or legacy_raw_smoke_requested
    ):
        return

    if "--help" in argv or "-h" in argv:
        print("PixelFlasher")
        print("Usage:")
        print("  python PixelFlasher.py                 Launch GUI")
        print("  python PixelFlasher.py --self-test     Run startup checks")
        print("  python PixelFlasher.py --doctor        Alias for --self-test")
        print("  python PixelFlasher.py --diagnostics   Create redacted diagnostics ZIP")
        print("  python PixelFlasher.py --ui-smoke-report PATH  Prove React/WebView startup")
        print("  python PixelFlasher.py --pty-smoke-report PATH Prove packaged PTY startup")
        print("  python PixelFlasher.py --legacy-raw-smoke-report PATH Prove Legacy Raw shell")
        print("  python PixelFlasher.py --version       Print version")
        raise SystemExit(0)

    if "--version" in argv or "-V" in argv:
        from constants import APPNAME, VERSION
        print(f"{APPNAME} {VERSION}")
        raise SystemExit(0)

    if "--self-test" in argv or "--doctor" in argv:
        from self_test import main as self_test_main
        filtered = [arg for arg in argv[1:] if arg not in {"--self-test", "--doctor"}]
        raise SystemExit(self_test_main(filtered))

    if "--diagnostics" in argv:
        from diagnostics import main as diagnostics_main
        filtered = [arg for arg in argv[1:] if arg != "--diagnostics"]
        raise SystemExit(diagnostics_main(filtered))

    if pty_smoke_requested:
        from pty_smoke_contract import main as pty_smoke_main
        raise SystemExit(pty_smoke_main(argv[1:]))

    if legacy_raw_smoke_requested:
        from legacy_raw_smoke_contract import main as legacy_raw_smoke_main
        raise SystemExit(legacy_raw_smoke_main(argv[1:]))

_run_cli_command(sys.argv)


def _run_modern_primary(argv):
    try:
        from ui.pages.modern_primary_app import launch_modern_primary
        result = launch_modern_primary(argv)
    except Exception as exc:
        _log_startup_failure(exc)
        print(f"Modern UI startup unavailable: {exc}")
        raise SystemExit(1) from exc
    raise SystemExit(result)


def _log_startup_failure(exc: Exception) -> None:
    try:
        path = os.path.join(tempfile.gettempdir(), "PixelFlasher-startup-error.log")
        with open(path, "a", encoding="utf-8", errors="replace") as log:
            log.write("PixelFlasher startup failed\n")
            log.write(f"{exc}\n")
            log.write(traceback.format_exc())
            log.write("\n")
    except Exception:
        pass


_run_modern_primary(sys.argv)
