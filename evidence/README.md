# Evidence store

Release gates in this project are closed by evidence, not by assertion. That
evidence used to live only in hosted CI artifacts, which expire; `build/` is
ignored, so nothing survived in the checkout either. A gate could therefore cite
a receipt that no longer existed anywhere.

Everything under this directory is a receipt produced by a gate, copied here and
bound to its SHA-256 and to the commit that produced it. `index.json` is the
manifest, written by `scripts/evidence_store.py`.

## Layout

| Path | Contents |
|---|---|
| `windows-x64/` | Packaged smoke receipts from the real `dist/PixelFlasher.exe` |
| `hardware/` | Sessions run against a physical device |
| `accessibility/` | Assistive-technology sessions |
| `index.json` | Record manifest: id, path, SHA-256, kind, commit, timestamp |

## Recording and confirming

```
python scripts/evidence_store.py add --source <receipt> --id windows-x64/pty-smoke --kind packaged-smoke
python scripts/evidence_store.py verify --expected-commit <sha>
```

`verify` fails closed when a recorded artifact is missing, no longer matches its
digest, or was recorded against a different commit. A receipt recorded against
an earlier commit is stale evidence, not passing evidence: re-run the gate that
produced it.

## What does not belong here

Private keys, downloaded upstream archives, device serial numbers, and anything
a support package would redact. Receipts are written by contracts that already
exclude host paths and secrets; do not hand-edit them.
