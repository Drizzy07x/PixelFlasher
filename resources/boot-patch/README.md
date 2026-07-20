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
KernelSU, KernelSU-Next, SukiSU and Wild_KSU. KernelSU Legacy kernel-image
replacement remains fail-closed until its KMI-specific image catalog is
implemented.
