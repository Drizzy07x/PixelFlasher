# Platform Tools release inputs

`source-lock.json` records the versioned Google stable archives and both the
upstream SHA-1 metadata plus independently calculated SHA-256 values. It is a
reviewable release input, not a runtime trust root.

The runtime consumes only `runtime/catalog.json` plus its signed target
manifests. Release engineering must provide an Ed25519 private key outside the
repository and pin its reviewed public half in
`pixelflasher_core/artifact_trust.py`. Run the catalog builder with
`resources/platform-tools/runtime` as its output. The builder refuses a key
whose derived public half is not already compiled into that trust root.

No private key, downloaded ZIP or accepted SDK license is stored here. A final
RC build must use the strict catalog verifier and fail if the signed catalog is
absent, expired or incomplete for the release matrix.

See `docs/platform-tools-release.md` for the release-key and catalog procedure.
