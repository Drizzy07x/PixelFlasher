# OTA fallback runner

`pf-ota-runner.dex` is a minimal, architecture-neutral client for Android's
system `UpdateEngine` API. It supports only `status`, `cancel`, and `reset`.
It exists for rooted devices whose production image does not ship the AOSP
`update_engine_client` debugging executable.

The checked-in DEX is generated from the owned Java source and compile-only
AOSP API stubs:

```text
python scripts/build_ota_runner.py
python scripts/build_ota_runner.py --check
```

The builder downloads the exact hash-locked R8/D8 artifact from Google's
Android Maven repository, compiles Java 8 bytecode, emits DEX for Android 8+
and verifies the committed output byte-for-byte. The stubs are not included
in the DEX; Android supplies the real framework classes at runtime.

The desktop runtime verifies the DEX SHA-256 before any ADB push. A release
still requires rooted real-device validation across the supported Pixel
Android range; source reproducibility does not substitute for that evidence.
