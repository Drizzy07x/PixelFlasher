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

__all__ = [
    "PLATFORM_TOOLS_ED25519_PUBLIC_KEYS",
    "ROOT_APP_ED25519_PUBLIC_KEYS",
]
