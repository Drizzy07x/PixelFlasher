"""Compatibility entrypoint for the non-interactive release version tool."""

from scripts.release_version import main


if __name__ == "__main__":
    raise SystemExit(main())
