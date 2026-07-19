# Built-in payload runner integrity

PixelFlasher 10 reconstructs Android full-update `payload.bin` images with the
packaged `pixelflasher_core.payload_extractor` runner. The runner accepts only
`REPLACE`, `REPLACE_BZ`, and `REPLACE_XZ`; it does not execute archive content,
shell commands, or third-party payload-dumper scripts.

At runtime, the runner canonicalizes its packaged source resource and verifies
its SHA-256 against `payload_extractor.integrity.json`. Extraction fails closed
when either resource is absent, malformed, or mismatched. PyInstaller specs
retain both resources so the check also runs in packaged applications.

This checkpoint deliberately does **not** claim release-signature provenance.
The repository does not yet have the Ed25519-signed release artifact manifest
specified for PixelFlasher 10. Until that manifest is implemented, this check
detects packaging mistakes and post-build resource tampering but inherits trust
from the build and signing pipeline. The future signed manifest must pin the
same canonical source digest; no extractor API change is required.
