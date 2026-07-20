#!/system/bin/sh
# PIXELFLASHER_BOOT_PATCH_RUNNER_V1
# PixelFlasher-owned Android boot patch protocol runner.

set -eu

fail() {
    printf '%s\n' "ERROR: $1" >&2
    exit 1
}

FLAVOR=''
INPUT=''
OUTPUT=''
APP=''
SUPPORT=''
EXPECTED_ARCH=''
EXPECTED_KMI=''
READ_SUPERKEY=0

[ "${1:-}" = 'patch' ] || fail 'expected patch command'
shift
while [ "$#" -gt 0 ]; do
    case "$1" in
        --flavor|--input|--output|--app|--support|--architecture|--kmi)
            [ "$#" -ge 2 ] || fail "missing value for $1"
            case "$1" in
                --flavor) FLAVOR=$2 ;;
                --input) INPUT=$2 ;;
                --output) OUTPUT=$2 ;;
                --app) APP=$2 ;;
                --support)
                    [ -z "$SUPPORT" ] || fail 'exactly one support binary is required'
                    SUPPORT=$2
                    ;;
                --architecture) EXPECTED_ARCH=$2 ;;
                --kmi) EXPECTED_KMI=$2 ;;
            esac
            shift 2
            ;;
        --superkey-stdin)
            [ "$READ_SUPERKEY" -eq 0 ] || fail 'duplicate superkey input flag'
            READ_SUPERKEY=1
            shift
            ;;
        *) fail "unknown argument: $1" ;;
    esac
done

case "$FLAVOR" in
    magisk|apatch|kernelsu|kernelsu-next|sukisu|wild-ksu) ;;
    *) fail 'unsupported patch flavor' ;;
esac
[ -n "$INPUT" ] && [ -n "$OUTPUT" ] && [ -n "$APP" ] || fail 'missing required path'
[ -n "$SUPPORT" ] || fail 'missing support binary'
case "$INPUT" in /data/local/tmp/pf-stock-*.img) ;; *) fail 'invalid input path' ;; esac
case "$OUTPUT" in /data/local/tmp/pf-patched-*.img) ;; *) fail 'invalid output path' ;; esac
case "$APP" in /data/local/tmp/pf-root-app-*.apk) ;; *) fail 'invalid app path' ;; esac
case "$SUPPORT" in /data/local/tmp/pf-patch-support-*) ;; *) fail 'invalid support path' ;; esac
[ -f "$INPUT" ] && [ -f "$APP" ] && [ -f "$SUPPORT" ] || fail 'required resource is missing'

# Android's system shell varies. Re-enter through the pinned BusyBox ash so
# provider scripts have one deterministic shell while stdin remains intact.
if [ "${PIXELFLASHER_PATCH_ASH:-0}" != '1' ]; then
    chmod 700 "$SUPPORT" || fail 'support binary is not executable'
    export PIXELFLASHER_PATCH_ASH=1
    set -- "$SUPPORT" ash "$0" patch \
        --flavor "$FLAVOR" --input "$INPUT" --output "$OUTPUT" \
        --app "$APP" --support "$SUPPORT" \
        --architecture "$EXPECTED_ARCH" --kmi "$EXPECTED_KMI"
    [ "$READ_SUPERKEY" -eq 0 ] || set -- "$@" --superkey-stdin
    exec "$@"
fi

canonical_arch() {
    case "$1" in
        arm64-v8a|aarch64|arm64) printf '%s' 'arm64' ;;
        armeabi-v7a|armeabi|armv7l|arm) printf '%s' 'arm' ;;
        x86_64|x86-64|amd64) printf '%s' 'x86_64' ;;
        x86|i386|i686) printf '%s' 'x86' ;;
        *) printf '%s' '' ;;
    esac
}

apk_abi() {
    case "$1" in
        arm64) printf '%s' 'arm64-v8a' ;;
        arm) printf '%s' 'armeabi-v7a' ;;
        x86_64) printf '%s' 'x86_64' ;;
        x86) printf '%s' 'x86' ;;
        *) printf '%s' '' ;;
    esac
}

OBSERVED_ARCH=$(canonical_arch "$(getprop ro.product.cpu.abi 2>/dev/null || true)")
[ -n "$OBSERVED_ARCH" ] || fail 'device architecture is unavailable'
[ -z "$EXPECTED_ARCH" ] || [ "$OBSERVED_ARCH" = "$EXPECTED_ARCH" ] \
    || fail 'device architecture changed'
ABI=$(apk_abi "$OBSERVED_ARCH")
[ -n "$ABI" ] || fail 'device architecture is unsupported'

WORK="/data/local/tmp/pf-runner-$$"
BB="$WORK/busybox"
APK_ROOT="$WORK/apk"
ASSETS="$WORK/assets"

cleanup() {
    if [ -x "$BB" ]; then
        "$BB" rm -rf "$WORK" >/dev/null 2>&1 || true
    else
        rm -rf "$WORK" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT HUP INT TERM

rm -rf "$WORK"
mkdir -p "$APK_ROOT" "$ASSETS"
cp "$SUPPORT" "$BB"
chmod 700 "$BB"
"$BB" unzip -q "$APP" -d "$APK_ROOT" || fail 'root app extraction failed'
[ -d "$APK_ROOT/assets" ] || fail 'root app assets are missing'
"$BB" cp -R "$APK_ROOT/assets/." "$ASSETS/"

FOUND_NATIVE=0
for LIBRARY in "$APK_ROOT/lib/$ABI"/lib*.so; do
    [ -f "$LIBRARY" ] || continue
    NAME=$("$BB" basename "$LIBRARY")
    NAME=${NAME#lib}
    NAME=${NAME%.so}
    [ -n "$NAME" ] || fail 'root app native library name is invalid'
    "$BB" cp "$LIBRARY" "$ASSETS/$NAME"
    FOUND_NATIVE=1
done
[ "$FOUND_NATIVE" -eq 1 ] || fail 'root app has no compatible native payload'
chmod 700 "$ASSETS"/* 2>/dev/null || true
cd "$ASSETS"
rm -f "$OUTPUT"

case "$FLAVOR" in
    magisk)
        [ "$READ_SUPERKEY" -eq 0 ] || fail 'Magisk does not accept a superkey'
        [ -f ./boot_patch.sh ] && [ -x ./magiskboot ] || fail 'Magisk patch assets are incomplete'
        SDK_INT=$(getprop ro.build.version.sdk 2>/dev/null || true)
        case "$SDK_INT" in ''|*[!0-9]*) fail 'Android SDK level is unavailable' ;; esac
        export SDK_INT
        set -- "$INPUT"
        . ./boot_patch.sh
        ;;
    apatch)
        [ "$READ_SUPERKEY" -eq 1 ] || fail 'APatch requires a superkey on stdin'
        IFS= read -r SUPERKEY || fail 'APatch superkey is unavailable'
        [ "${#SUPERKEY}" -ge 8 ] && [ "${#SUPERKEY}" -le 128 ] || fail 'APatch superkey length is invalid'
        [ -f ./boot_patch.sh ] && [ -x ./magiskboot ] || fail 'APatch patch assets are incomplete'
        set -- "$SUPERKEY" "$INPUT" -K kpatch
        . ./boot_patch.sh
        SUPERKEY=''
        ;;
    kernelsu|kernelsu-next|sukisu|wild-ksu)
        [ "$READ_SUPERKEY" -eq 0 ] || fail 'KernelSU patchers do not accept a superkey'
        PATCHER=''
        for CANDIDATE in ksud zakozako; do
            if [ -x "./$CANDIDATE" ]; then PATCHER="./$CANDIDATE"; break; fi
        done
        [ -n "$PATCHER" ] || fail 'KernelSU patcher is missing'
        HELP=$($PATCHER boot-patch --help 2>&1 || true)
        set -- "$PATCHER" boot-patch -b "$INPUT" --allow-shell
        case "$HELP" in
            *--magiskboot*) [ -x ./magiskboot ] && set -- "$@" --magiskboot ./magiskboot ;;
        esac
        case "$HELP" in
            *--kmi*) [ -n "$EXPECTED_KMI" ] && set -- "$@" --kmi "$EXPECTED_KMI" ;;
        esac
        "$@" >"$WORK/patch.log" 2>&1 || fail 'KernelSU patcher failed'
        ;;
esac

CANDIDATE=''
COUNT=0
for IMAGE in "$ASSETS"/*.img; do
    [ -f "$IMAGE" ] || continue
    case "$IMAGE" in *new-boot.img|*patched*.img|*kernelsu*.img)
        CANDIDATE=$IMAGE
        COUNT=$((COUNT + 1))
        ;;
    esac
done
[ "$COUNT" -eq 1 ] || fail 'patcher did not produce one unambiguous image'
[ -s "$CANDIDATE" ] || fail 'patched image is empty'
"$BB" cp "$CANDIDATE" "$OUTPUT"
[ -s "$OUTPUT" ] || fail 'patched output publication failed'
printf '%s\n' 'PIXELFLASHER_PATCH_COMPLETE'
