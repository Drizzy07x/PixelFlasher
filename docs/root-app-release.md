# Root application release signing

PixelFlasher 10 downloads root managers only from an authenticated catalog.
The Ed25519 public key is compiled into the application; neither the catalog
nor the WebView can add or replace trusted keys.

## Production-key provisioning

1. Generate and custody the Ed25519 private key outside the repository and CI
   workspace.
2. Review the raw 32-byte public key through the release-security process.
3. Add that key under a stable ID to
   `pixelflasher_core/artifact_trust.py`.
4. Keep both public keys pinned during a rotation window.

Never commit the private key or downloaded APKs.

## Audit and build

The source lock records one stable, non-spoofed APK for all seven providers.
Repeat the network audit when updating it:

```powershell
python scripts/audit_root_app_releases.py --pretty
```

Download those exact APKs into private staging. The offline builder verifies
size, SHA-256, package ID, signing certificate, signature schemes and native
ABIs before it signs any manifest:

```powershell
python scripts/build_root_app_catalog.py `
  --source-lock resources/root-apps/source-lock.json `
  --private-key D:\release-secrets\root-apps-ed25519.pem `
  --key-id root-apps-release-2026 `
  --apks D:\release-staging\root-apps `
  --output resources/root-apps/runtime `
  --expires-at 2027-07-01T00:00:00Z
```

The runtime loader treats a missing catalog as optional only in migration
builds. Any partial, malformed, expired or unauthenticated directory fails
closed. A `v10.*` release must run the strict verifier:

```powershell
python scripts/verify_root_app_catalog.py `
  --root resources/root-apps/runtime
```

The verifier requires all 13 audited provider/architecture targets. Real
download, install and patch smokes on supported Android devices remain a
separate release gate.
