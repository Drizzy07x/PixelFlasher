# Platform Tools release signing

PixelFlasher 10 authenticates its Platform Tools catalog with an Ed25519 public
key compiled into the application. The catalog cannot add or replace trusted
keys.

## One-time production-key provisioning

1. Generate and custody the Ed25519 private key outside the repository and CI
   workspace.
2. Review the raw 32-byte public key through the release-security process.
3. Add that public key under a stable key ID in
   `pixelflasher_core/artifact_trust.py`.
4. Use a dual-key interval when rotating keys. Remove the old key only after no
   supported catalog or release depends on it.

Private keys, downloaded archives and accepted Android SDK licenses must never
be committed or included in support packages.

## Build the signed catalog

Download the three archives named in
`resources/platform-tools/source-lock.json` into a private staging directory.
The builder is offline: it verifies their exact size, upstream SHA-1, SHA-256,
archive structure, version and binary architectures before signing.

```powershell
python scripts/build_platform_tools_catalog.py `
  --source-lock resources/platform-tools/source-lock.json `
  --private-key D:\release-secrets\platform-tools-ed25519.pem `
  --key-id platform-tools-release-2026 `
  --archives D:\release-staging\platform-tools `
  --output resources/platform-tools/runtime `
  --expires-at 2027-07-01T00:00:00Z
```

The output must contain `catalog.json` and one signed manifest for each of:

- Windows x64 and ARM64 hosts;
- macOS Intel and Apple Silicon hosts;
- Linux x86_64 hosts.

The Windows manifests intentionally describe Google's official PE x86
binaries, which execute through the Windows compatibility layer on both
supported host architectures. They are not mislabeled as native ARM64.

## Release verification

Run the verifier without `--allow-missing`:

```powershell
python scripts/verify_platform_tools_catalog.py `
  --root resources/platform-tools/runtime
```

Every `v10.*` packaging path runs this strict form automatically. Migration
builds may use `--allow-missing`, but a partial, malformed, expired or
unauthenticated runtime directory always fails closed.

After verification, execute the packaged install/activation smoke on every
release target. A successful catalog check alone does not promote
`platform_tools.setup` to `native`.
