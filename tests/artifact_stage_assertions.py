from __future__ import annotations

import hashlib
import re
import unittest
from collections.abc import Iterable
from pathlib import Path

from pixelflasher_core.contracts import ProcessRequest

_STAGED_NAME = re.compile(r"^\d{4}-([0-9a-f]{64})(\.(?:apk|bin|img|zip))$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def assert_exact_or_staged_argv(
    case: unittest.TestCase,
    expected: Iterable[tuple[str, ...]],
    actual: Iterable[tuple[str, ...] | ProcessRequest],
) -> None:
    """Assert exact argv, allowing only hash-bound private artifact copies."""

    expected_requests = tuple(expected)
    actual_requests = tuple(
        item.argv if isinstance(item, ProcessRequest) else item for item in actual
    )
    case.assertEqual(len(expected_requests), len(actual_requests))
    for expected_argv, actual_argv in zip(
        expected_requests,
        actual_requests,
        strict=True,
    ):
        case.assertEqual(len(expected_argv), len(actual_argv))
        for expected_argument, actual_argument in zip(
            expected_argv,
            actual_argv,
            strict=True,
        ):
            if expected_argument == actual_argument:
                continue
            source = Path(expected_argument)
            case.assertTrue(
                source.is_file(),
                f"non-artifact argv changed: {expected_argument!r} != {actual_argument!r}",
            )
            staged = Path(actual_argument)
            case.assertTrue(
                staged.parent.name.startswith("pixelflasher-artifacts-"),
                f"artifact was not executed from private staging: {actual_argument}",
            )
            match = _STAGED_NAME.fullmatch(staged.name)
            case.assertIsNotNone(match, f"staged artifact name is not canonical: {staged.name}")
            assert match is not None
            case.assertEqual(_sha256(source), match.group(1))
            expected_suffix = source.suffix.casefold()
            if expected_suffix not in {".apk", ".bin", ".img", ".zip"}:
                expected_suffix = ".bin"
            case.assertEqual(expected_suffix, match.group(2))
