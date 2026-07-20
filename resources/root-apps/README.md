# Root application release inputs

`source-lock.json` records the stable, non-spoofed APK selected from each
provider's official GitHub release. Every entry includes the GitHub-published
SHA-256 and size plus the package ID, signing certificate, signature schemes
and native ABIs independently verified by PixelFlasher's bounded APK
inspector.

Run `python scripts/audit_root_app_releases.py --pretty` to redownload the
pinned assets into temporary storage and repeat the inspection. No APK is
retained or committed.

This file is a reviewable release input, not the runtime trust root. Release
engineering must convert it into expiring Ed25519-signed artifact manifests;
the private key stays outside the repository and the reviewed public key is
pinned in `pixelflasher_core/artifact_trust.py`.
