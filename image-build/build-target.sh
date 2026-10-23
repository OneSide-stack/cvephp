#!/usr/bin/env bash
set -Eeuo pipefail
trap 'rc=$?; printf "::error::Target image build failed at line %s: %s (exit %s)\\n" "$LINENO" "$BASH_COMMAND" "$rc" >&2; exit "$rc"' ERR
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PHP_VERSION="${1:-8.2.34}"
ALPINE_VERSION="${ALPINE_VERSION:-3.22.1}"
OUT_NAME="${2:-target-php-${PHP_VERSION}.iso}"
DOWNLOADS="$ROOT/image-build/downloads"
WORK="$ROOT/.image-build-work/target-$PHP_VERSION"
OUT="$ROOT/public/lab-assets/$OUT_NAME"
PHP_ARCHIVE="$DOWNLOADS/php-$PHP_VERSION.tar.gz"
ALPINE_ISO="$DOWNLOADS/alpine-standard-$ALPINE_VERSION-x86.iso"
BASE_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION%.*}/releases/x86"
mkdir -p "$DOWNLOADS" "$WORK" "$(dirname "$OUT")"

fetch() { curl -fL --retry 4 --retry-delay 2 "$1" -o "$2"; }
if [[ ! -s "$PHP_ARCHIVE" ]]; then
  fetch "https://codeload.github.com/php/php-src/tar.gz/refs/tags/php-$PHP_VERSION" "$PHP_ARCHIVE"
fi
expected="$(awk -v name="php-$PHP_VERSION.tar.gz" '$2 == name {print $1}' "$ROOT/image-build/target/php-source.sha256")"
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { echo "No pinned SHA-256 for PHP $PHP_VERSION" >&2; exit 1; }
echo "$expected  $PHP_ARCHIVE" | sha256sum -c -
if [[ ! -s "$ALPINE_ISO" ]]; then
  fetch "$BASE_URL/alpine-standard-$ALPINE_VERSION-x86.iso" "$ALPINE_ISO"
fi
fetch "$BASE_URL/alpine-standard-$ALPINE_VERSION-x86.iso.sha256" "$ALPINE_ISO.sha256"
expected_iso="$(awk -v name="alpine-standard-$ALPINE_VERSION-x86.iso" '$2 == name || $2 == "*" name {print $1}' "$ALPINE_ISO.sha256")"
[[ "$expected_iso" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "Could not verify Alpine ISO checksum format" >&2; exit 1; }
echo "${expected_iso,,}  $ALPINE_ISO" | sha256sum -c -

# Compile PHP and construct the actual Alpine root filesystem. No packages are
# fetched by the learner or by either running guest.
docker build --platform linux/386 \
  --build-arg "PHP_VERSION=$PHP_VERSION" \
  --build-arg "ALPINE_VERSION=$ALPINE_VERSION" \
  --build-arg "PHP_SOURCE_SHA256=$expected" \
  --build-arg "BUILD_EPOCH=${SOURCE_DATE_EPOCH:-0}" \
  -f "$ROOT/image-build/target/Dockerfile" \
  -t "cyber-range-target:$PHP_VERSION" "$ROOT"

rm -rf "$WORK/rootfs" "$WORK/iso" "$WORK/base"
mkdir -p "$WORK/rootfs" "$WORK/iso" "$WORK/base"
container="$(docker create --platform linux/386 "cyber-range-target:$PHP_VERSION")"
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT
docker export "$container" -o "$WORK/rootfs.tar"
tar -xf "$WORK/rootfs.tar" -C "$WORK/rootfs"
tar -f "$WORK/rootfs.tar" --delete .dockerenv 2>/dev/null || true
[[ -x "$WORK/rootfs/bin/busybox" && -x "$WORK/rootfs/usr/local/bin/php" ]] || { echo 'Target rootfs verification failed' >&2; exit 1; }

# Use official Alpine boot media, replacing only its initramfs with the prepared
# target rootfs. The same kernel and rootfs are therefore bootable under QEMU.
docker run --rm --platform linux/amd64 \
  -v "$ROOT:/work" -v "$DOWNLOADS:/downloads" alpine:3.22.1 sh -eu -c '
    apk add --no-cache xorriso >/dev/null
    xorriso -osirrox on -indev "/downloads/'"$(basename "$ALPINE_ISO")"'" -extract /boot /work/.image-build-work/target-'"$PHP_VERSION"'/base/boot >/dev/null 2>&1
  '
cp -a "$WORK/base/boot" "$WORK/iso/"
(
  cd "$WORK/rootfs"
  find . -path './dev' -prune -o -path './proc' -prune -o -path './sys' -prune -o -path './run' -prune -o -print0
) | docker run --rm -i --platform linux/amd64 -v "$WORK:/work" alpine:3.22.1 sh -c '
  apk add --no-cache cpio gzip >/dev/null
  cd /work/rootfs && cpio --null -o -H newc | gzip -9 > /work/initramfs-lts
'
cp "$WORK/initramfs-lts" "$WORK/iso/boot/initramfs-lts"
# Enable both the visible VGA console and hidden serial control channel.
find "$WORK/iso" -name 'isolinux.cfg' -o -name 'syslinux.cfg' | while read -r cfg; do
  sed -i 's/console=tty0/console=tty0 console=ttyS0,115200/g' "$cfg"
  grep -q 'console=ttyS0' "$cfg" || sed -i 's/append /append console=tty0 console=ttyS0,115200 /I' "$cfg"
done
isolinux="$(find "$WORK/iso" -name isolinux.bin -print -quit)"
[[ -n "$isolinux" ]] || { echo 'isolinux.bin missing from Alpine media' >&2; exit 1; }
rel="${isolinux#"$WORK/iso/"}"
bootcat="$(dirname "$rel")/boot.cat"
docker run --rm --platform linux/amd64 -v "$WORK/iso:/iso" -v "$(dirname "$OUT"):/output" alpine:3.22.1 sh -c '
  apk add --no-cache xorriso >/dev/null
  xorriso -as mkisofs -R -J -V CYBER_RANGE_TARGET -b "'"$rel"'" -c "'"$bootcat"'" -no-emul-boot -boot-load-size 4 -boot-info-table -o "/output/'"$(basename "$OUT")"'" /iso >/dev/null
'
[[ -s "$OUT" ]] || { echo 'No target ISO produced' >&2; exit 1; }
sha256sum "$OUT"
ls -lh "$OUT"
