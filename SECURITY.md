# Security policy

## Supported versions

The latest stable release and current 10.x release candidate receive security
fixes. Older releases should be upgraded before requesting support.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature. Do not include device
serials, pairing codes, private keys, tokens or unredacted support archives in
public issues.

Reports should include the affected version, platform, reproducible behavior
and security impact. Acknowledgement is targeted within seven days. Disclosure
is coordinated after a signed fix is available.

PixelFlasher does not execute device mutations outside `SafetyPolicy`, does not
accept browser-provided filesystem paths and does not enable telemetry by
default. Release checksums and provenance must be verified before installation.
