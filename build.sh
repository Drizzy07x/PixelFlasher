#!/usr/bin/env bash

# Copyright (C) 2025 Badabing2005
# SPDX-FileCopyrightText: 2025 Badabing2005
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
# for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Also add information on how to contact you by electronic and paper mail.
#
# If your software can interact with users remotely through a computer network,
# you should also make sure that it provides a way for users to get its source.
# For example, if your program is a web application, its interface could
# display a "Source" link that leads users to an archive of the code. There are
# many ways you could offer source, and different solutions will be better for
# different programs; see section 13 for the specific requirements.
#
# You should also get your employer (if you work as a programmer) or school, if
# any, to sign a "copyright disclaimer" for the program, if necessary. For more
# information on this, and how to apply and follow the GNU AGPL, see
# <https://www.gnu.org/licenses/>.

pushd "$(dirname "$0")"

rm -rf build dist
NAME="PixelFlasher"
DIST_NAME="PixelFlasher"

if [[ $OSTYPE == 'darwin'* ]]; then
    if [[ $(arch) == 'arm64' ]]; then
        echo "Building native macOS Apple Silicon binary"
        specfile=build-on-mac.spec
    else
        echo "Building for macOS"
        specfile=build-on-mac-intel-only.spec
    fi
else
    echo "Building for Linux"
    specfile=build-on-linux.spec
fi

if ! command -v python3 &> /dev/null
then
    PYTHON=python
else
    PYTHON=python3
fi
VERSION=$($PYTHON - <<'PY'
from constants import VERSION
print(VERSION)
PY
)
$PYTHON ./compile_po.py

if [[ ${PIXELFLASHER_FRONTEND_PREBUILT:-0} == "1" ]]; then
    $PYTHON ./scripts/build_frontend.py --check-only
else
    $PYTHON ./scripts/build_frontend.py
fi

if [[ ${GITHUB_REF:-} == refs/tags/v10.* ]]; then
    PIXELFLASHER_REQUIRE_SIGNED_PLATFORM_TOOLS=1
fi
catalog_args=(--root resources/platform-tools/runtime)
if [[ ${PIXELFLASHER_REQUIRE_SIGNED_PLATFORM_TOOLS:-0} != "1" ]]; then
    catalog_args+=(--allow-missing)
fi
$PYTHON ./scripts/verify_platform_tools_catalog.py "${catalog_args[@]}"
if [[ $? -ne 0 ]]; then
    exit 1
fi
root_app_catalog_args=(--root resources/root-apps/runtime)
firmware_catalog_args=(--root resources/firmware/runtime)
scrcpy_catalog_args=(--root resources/scrcpy/runtime)
update_manifest_args=(--path resources/updates/runtime/manifest.json)
keybox_revocation_args=(--path resources/keybox/revocations.json)
if [[ ${PIXELFLASHER_REQUIRE_SIGNED_PLATFORM_TOOLS:-0} != "1" ]]; then
    root_app_catalog_args+=(--allow-missing)
    firmware_catalog_args+=(--allow-missing)
    scrcpy_catalog_args+=(--allow-missing)
    update_manifest_args+=(--allow-missing)
    keybox_revocation_args+=(--allow-missing)
fi
$PYTHON ./scripts/verify_root_app_catalog.py "${root_app_catalog_args[@]}" || exit 1
$PYTHON ./scripts/verify_firmware_catalog.py "${firmware_catalog_args[@]}" || exit 1
$PYTHON ./scripts/verify_scrcpy_catalog.py "${scrcpy_catalog_args[@]}" || exit 1
$PYTHON ./scripts/verify_update_manifest.py "${update_manifest_args[@]}" || exit 1
$PYTHON ./scripts/verify_keybox_revocations.py "${keybox_revocation_args[@]}" || exit 1

pyinstaller --log-level=DEBUG \
            --noconfirm \
            $specfile

if [[ $OSTYPE == 'darwin'* && ${PIXELFLASHER_SKIP_DMG:-0} != "1" ]]; then
    # https://github.com/sindresorhus/create-dmg
    echo "List before creating DMG"
    ls -l ./ dist/
    chmod +x dist/$NAME.app/Contents/MacOS/$NAME
    create-dmg "dist/$NAME.app"
    echo "List after creating DMG"
    ls -l ./ dist/
    dmg_source="$NAME $VERSION.dmg"
    if [[ ! -f "$dmg_source" ]]; then
        dmg_source=$(find . -maxdepth 1 -name "$NAME*.dmg" -print -quit)
    fi
    mv "$dmg_source" "dist/$DIST_NAME.dmg"
fi

popd
ls -l build/ dist/

