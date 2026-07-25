"""Public artifact-signing trust roots compiled into PixelFlasher."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

# Release engineering must add reviewed raw Ed25519 public keys here before a
# signed Platform Tools catalog can be accepted. Keeping the trust root in code
# prevents a replaced resource catalog from authorizing its own signing key.
PLATFORM_TOOLS_ED25519_PUBLIC_KEYS: Mapping[str, bytes] = MappingProxyType({})

# Root-application manifests use an independent release key so compromise or
# rotation of one artifact family cannot authorize another.  Release
# engineering must add the reviewed public key before packaging runtime data.
ROOT_APP_ED25519_PUBLIC_KEYS: Mapping[str, bytes] = MappingProxyType({})

# Firmware, Scrcpy, and application-update metadata each use an independent
# release key. Release engineering provisions reviewed raw Ed25519 public keys
# here; runtime catalogs can never introduce or replace their own trust roots.
FIRMWARE_ED25519_PUBLIC_KEYS: Mapping[str, bytes] = MappingProxyType({})
SCRCPY_ED25519_PUBLIC_KEYS: Mapping[str, bytes] = MappingProxyType({})
UPDATE_ED25519_PUBLIC_KEYS: Mapping[str, bytes] = MappingProxyType({})
KEYBOX_REVOCATION_ED25519_PUBLIC_KEYS: Mapping[str, bytes] = MappingProxyType({})

__all__ = [
    "FIRMWARE_ED25519_PUBLIC_KEYS",
    "KEYBOX_REVOCATION_ED25519_PUBLIC_KEYS",
    "PLATFORM_TOOLS_ED25519_PUBLIC_KEYS",
    "ROOT_APP_ED25519_PUBLIC_KEYS",
    "SCRCPY_ED25519_PUBLIC_KEYS",
    "UPDATE_ED25519_PUBLIC_KEYS",
]
