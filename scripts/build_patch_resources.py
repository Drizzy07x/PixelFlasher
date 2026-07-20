"""Build the reproducible packaged boot-patch runner manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path

ARCHITECTURES = {
    "arm64": "bin/busybox_arm64-v8a",
    "arm": "bin/busybox_armeabi-v7a",
    "x86": "bin/busybox_x86",
    "x86_64": "bin/busybox_x86_64",
}
FLAVORS = ("magisk", "apatch", "kernelsu", "kernelsu-next", "sukisu", "wild-ksu")
PROTOCOL = "pixelflasher.boot-patch.v1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_atomic(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def build(application_root: Path) -> tuple[Path, str]:
    root = application_root.resolve(strict=True)
    runner_path = root / "resources" / "boot-patch" / "runner" / "pf_boot_patch.sh"
    runner_hash = _sha256(runner_path)
    bundles = []
    for flavor in FLAVORS:
        for architecture, support_name in ARCHITECTURES.items():
            support_path = root / support_name
            bundles.append(
                {
                    "flavor": flavor,
                    "runner": {
                        "path": "resources/boot-patch/runner/pf_boot_patch.sh",
                        "sha256": runner_hash,
                    },
                    "support": [
                        {"path": support_name, "sha256": _sha256(support_path)}
                    ],
                    "compatibility": {
                        "architectures": [architecture],
                        "kmi": ["*"],
                    },
                }
            )
    document = {
        "schemaVersion": 3,
        "protocol": PROTOCOL,
        "bundles": bundles,
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    output = root / "resources" / "boot-patch" / "runtime" / "patch-resources.json"
    _write_atomic(output, encoded)
    digest = hashlib.sha256(encoded).hexdigest()
    _write_atomic(output.with_suffix(".sha256"), f"{digest}\n".encode("ascii"))
    return output, digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    output, digest = build(args.root)
    print(f"{output}: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
