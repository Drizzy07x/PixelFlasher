"""Public artifact-signing trust roots compiled into PixelFlasher."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

# Release engineering must add reviewed raw Ed25519 public keys here before a
# signed Platform Tools catalog can be accepted. Keeping the trust root in code
# prevents a replaced resource catalog from authorizing its own signing key.
PLATFORM_TOOLS_ED25519_PUBLIC_KEYS: Mapping[str, bytes] = MappingProxyType(
    {
        "platform-tools-release-2026": bytes.fromhex(
            "697641f6ebf73f68437bd497ab9c75be08fc9c60eb8191f467e417520d320816"
        ),
    }
)

# Root-application manifests use an independent release key so compromise or
# rotation of one artifact family cannot authorize another.  Release
# engineering must add the reviewed public key before packaging runtime data.
ROOT_APP_ED25519_PUBLIC_KEYS: Mapping[str, bytes] = MappingProxyType(
    {
        "root-apps-release-2026": bytes.fromhex(
            "e81f0968fdb7e1b2a546d5e6829819705b15da535ac6f6bce593647879a7f04d"
        ),
    }
)

# Firmware, Scrcpy, and application-update metadata each use an independent
# release key. Release engineering provisions reviewed raw Ed25519 public keys
# here; runtime catalogs can never introduce or replace their own trust roots.
FIRMWARE_ED25519_PUBLIC_KEYS: Mapping[str, bytes] = MappingProxyType(
    {
        "firmware-release-2026": bytes.fromhex(
            "051c46202b7e4317e0f3f3de260770df8eff877168574930b55f45473ea60edd"
        ),
    }
)
SCRCPY_ED25519_PUBLIC_KEYS: Mapping[str, bytes] = MappingProxyType(
    {
        "scrcpy-release-2026": bytes.fromhex(
            "ae9f7384f92db1ed181f1f19dcc12dcdc878d6cd2c3ba0d6341109287df3474d"
        ),
    }
)
UPDATE_ED25519_PUBLIC_KEYS: Mapping[str, bytes] = MappingProxyType(
    {
        "updates-release-2026": bytes.fromhex(
            "99779f844fc4484edc2fb976cf2914a3efb95707b1a050b2b6d0a8ac867d1aaa"
        ),
    }
)
KEYBOX_REVOCATION_ED25519_PUBLIC_KEYS: Mapping[str, bytes] = MappingProxyType(
    {
        "keybox-release-2026": bytes.fromhex(
            "8cafb4138ffa9346513ba203fa13bafe1f3f393fef64b85abb8b09e1a76d6962"
        ),
    }
)

__all__ = [
    "FIRMWARE_ED25519_PUBLIC_KEYS",
    "KEYBOX_REVOCATION_ED25519_PUBLIC_KEYS",
    "PLATFORM_TOOLS_ED25519_PUBLIC_KEYS",
    "ROOT_APP_ED25519_PUBLIC_KEYS",
    "SCRCPY_ED25519_PUBLIC_KEYS",
    "UPDATE_ED25519_PUBLIC_KEYS",
]
