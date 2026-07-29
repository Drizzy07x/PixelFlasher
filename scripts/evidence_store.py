#!/usr/bin/env python3
"""Record gate evidence inside the repository instead of ephemeral CI storage.

Hosted artifacts expire, and `build/` is ignored, so every receipt a release gate
cited used to disappear once its run aged out. This module keeps each receipt
under `evidence/`, bound to its SHA-256 and to the commit that produced it, so a
gate can be re-verified later from the checkout alone.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_ROOT = REPOSITORY_ROOT / "evidence"
INDEX_PATH = EVIDENCE_ROOT / "index.json"
SCHEMA_VERSION = 1

KINDS = frozenset(
    {
        "packaged-smoke",
        "hardware-session",
        "accessibility-session",
        "source-quality",
    }
)


class EvidenceError(RuntimeError):
    """The evidence store cannot accept or confirm a record."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def head_commit(root: Path = REPOSITORY_ROOT) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ("git", "rev-parse", "HEAD"),
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise EvidenceError("unable to resolve HEAD")
    return completed.stdout.strip().lower()


def load_index() -> dict[str, object]:
    if not INDEX_PATH.is_file():
        return {"schemaVersion": SCHEMA_VERSION, "records": []}
    try:
        document = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"evidence index is unreadable: {error}") from error
    if not isinstance(document, dict) or document.get("schemaVersion") != SCHEMA_VERSION:
        raise EvidenceError("evidence index has an unexpected schema")
    if not isinstance(document.get("records"), list):
        raise EvidenceError("evidence index has no record list")
    return document


def _write_index(document: Mapping[str, object]) -> None:
    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
    temporary = INDEX_PATH.with_suffix(".json.tmp")
    temporary.write_text(payload, encoding="utf-8", newline="\n")
    temporary.replace(INDEX_PATH)


def record(
    source: Path,
    *,
    record_id: str,
    kind: str,
    commit: str | None = None,
    attributes: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Copy `source` under evidence/ and bind it to its digest and commit."""

    if kind not in KINDS:
        raise EvidenceError(f"unknown evidence kind {kind!r}")
    if not record_id or record_id.strip("/") != record_id or "\\" in record_id:
        raise EvidenceError(f"record id must be a relative posix path, found {record_id!r}")
    source = Path(source)
    if not source.is_file():
        raise EvidenceError(f"evidence source is missing: {source}")

    destination = EVIDENCE_ROOT / f"{record_id}.json"
    if not destination.resolve().is_relative_to(EVIDENCE_ROOT.resolve()):
        raise EvidenceError("record id escapes the evidence store")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(source.read_bytes())

    entry: dict[str, object] = {
        "id": record_id,
        "path": destination.relative_to(REPOSITORY_ROOT).as_posix(),
        "sha256": sha256_file(destination),
        "kind": kind,
        "recordedCommit": commit or head_commit(),
        "recordedAt": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if attributes:
        entry["attributes"] = dict(sorted(attributes.items()))

    document = load_index()
    records = [item for item in document["records"] if item.get("id") != record_id]  # type: ignore[union-attr]
    records.append(entry)
    document["records"] = sorted(records, key=lambda item: str(item.get("id")))
    _write_index(document)
    return entry


def verify(*, commit: str | None = None) -> tuple[str, ...]:
    """Confirm every recorded artifact still exists and matches its digest."""

    document = load_index()
    expected_commit = commit
    problems: list[str] = []
    for entry in document["records"]:  # type: ignore[union-attr]
        if not isinstance(entry, dict):
            problems.append("index contains a malformed record")
            continue
        identifier = str(entry.get("id"))
        path = REPOSITORY_ROOT / str(entry.get("path", ""))
        if not path.is_file():
            problems.append(f"{identifier}: recorded artifact is missing")
            continue
        if sha256_file(path) != entry.get("sha256"):
            problems.append(f"{identifier}: artifact no longer matches its recorded digest")
        if expected_commit and entry.get("recordedCommit") != expected_commit:
            problems.append(
                f"{identifier}: recorded against {entry.get('recordedCommit')}, expected {expected_commit}"
            )
    return tuple(problems)


def records_of_kind(kind: str) -> tuple[dict[str, object], ...]:
    document = load_index()
    return tuple(
        entry
        for entry in document["records"]  # type: ignore[union-attr]
        if isinstance(entry, dict) and entry.get("kind") == kind
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)

    add = subparsers.add_parser("add", help="record an artifact")
    add.add_argument("--source", type=Path, required=True)
    add.add_argument("--id", dest="record_id", required=True)
    add.add_argument("--kind", required=True, choices=sorted(KINDS))
    add.add_argument("--attribute", action="append", default=[], metavar="KEY=VALUE")

    check = subparsers.add_parser("verify", help="confirm recorded artifacts are intact")
    check.add_argument("--expected-commit")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.action == "add":
            attributes: dict[str, str] = {}
            for item in args.attribute:
                key, separator, value = item.partition("=")
                if not separator or not key:
                    raise EvidenceError(f"attribute must be KEY=VALUE, found {item!r}")
                attributes[key] = value
            entry = record(
                args.source,
                record_id=args.record_id,
                kind=args.kind,
                attributes=attributes or None,
            )
            print(f"recorded {entry['id']} -> {entry['path']} ({entry['sha256'][:12]})")
            return 0
        problems = verify(commit=args.expected_commit)
    except EvidenceError as error:
        print(f"error: {error}")
        return 1
    if problems:
        for problem in problems:
            print(f"[BLOCK] {problem}")
        return 1
    print("evidence store verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
