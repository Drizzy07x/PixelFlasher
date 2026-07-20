# Packaged boot-patch runner

`runner/pf_boot_patch.sh` is PixelFlasher's owned Android-side implementation
of `pixelflasher.boot-patch.v1`. It accepts only backend-created temporary
paths, never evaluates a command string, and consumes an APatch superkey only
from stdin.

Run `python scripts/build_patch_resources.py` to regenerate the checked-in
runtime manifest. The manifest binds the runner and the existing per-ABI
BusyBox support binaries by SHA-256. Provider APKs are intentionally absent:
they belong to the separately signed, on-demand root-app catalog and are
validated by hash, package ID and signer before this runner can receive them.

The current runner covers Magisk, APatch and the app-provided LKM patchers for
KernelSU, KernelSU-Next, SukiSU and Wild_KSU. The pinned official KernelSU
Legacy release publishes only its manager APK: it contains neither a
KMI-specific kernel image nor a usable `kernelsu.ko`. The audited absence and
official source references are recorded in `kernelsu-legacy-assessment.json`.
Legacy remains fail-closed until a reproducible compatible kernel/module input
and its device/KMI policy are available.
