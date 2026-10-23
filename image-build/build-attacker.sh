#!/usr/bin/env bash
set -Eeuo pipefail
trap 'rc=$?; printf "::error::Attacker image build failed at line %s: %s (exit %s)\\n" "$LINENO" "$BASH_COMMAND" "$rc" >&2; exit "$rc"' ERR
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOWNLOADS="$ROOT/image-build/downloads"
WORK="$ROOT/.image-build-work/attacker"
OUT="$ROOT/public/lab-assets/attacker-tinycore-11.0.iso"
BASE="$DOWNLOADS/TinyCore-11.0.iso"
BASE_SHA256=778fc3788d9df3de72970827968b2b195aca827401db6f6f9cbdb737d4300bda
mkdir -p "$DOWNLOADS" "$WORK" "$(dirname "$OUT")"
if [[ ! -s "$BASE" ]]; then
  # The publisher now retains only 11.1 in this directory. Keep the lab on its
  # documented 11.0 profile and authenticate this immutable third-party mirror
  # with the independently recorded digest below; never follow a floating ISO.
  curl -fL --retry 4 --retry-delay 2 -H 'Accept: application/vnd.github.raw+json' "https://api.github.com/repos/alizafarbati/WebLinux/git/blobs/45166e33208626dc6074f20ba0dbd8824d113358" -o "$BASE"
fi
echo "$BASE_SHA256  $BASE" | sha256sum -c -
python3 "$ROOT/image-build/fetch-tinycore.py"
rm -rf "$WORK/iso" "$WORK/core"
mkdir -p "$WORK/iso" "$WORK/core"

docker run --rm --platform linux/amd64 \
  -v "$ROOT:/work" -v "$DOWNLOADS:/downloads" alpine:3.22.1 sh -eu -c '
    apk add --no-cache xorriso cpio gzip >/dev/null
    xorriso -osirrox on -indev /downloads/TinyCore-11.0.iso -extract / /work/.image-build-work/attacker/iso >/dev/null 2>&1
    cd /work/.image-build-work/attacker/core
    gzip -dc ../iso/boot/core.gz | cpio -idmu >/dev/null 2>&1
  '
# cpio runs as root in the utility container. Return the extracted tree to the
# host user and normalize read-only ISO modes before install/sed/cp operations;
# otherwise existing root-owned or read-only files cannot be replaced on the runner.
docker run --rm --platform linux/amd64 \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  -v "$WORK:/work" alpine:3.22.1 \
  sh -c 'chown -R "$HOST_UID:$HOST_GID" /work/core /work/iso && chmod -R u+rwX /work/core /work/iso'

CORE="$WORK/core"
ISO="$WORK/iso"
# The extracted base is allowed to omit empty directories. Create every
# overlay destination explicitly; install(1) does not create parent directories.
mkdir -p "$CORE/opt" "$CORE/usr/local/bin" "$CORE/etc"
install -m 0755 "$ROOT/image-build/attacker/bootlocal.sh" "$CORE/opt/bootlocal.sh"
install -m 0755 "$ROOT/image-build/attacker/labctl" "$CORE/usr/local/bin/labctl"
install -m 0755 "$ROOT/image-build/attacker/lab-console" "$CORE/usr/local/bin/lab-console"
mkdir -p "$CORE/home/tc/lab" "$CORE/home/tc/.dillo" "$CORE/home/tc/.X.d"
install -m 0755 "$ROOT/image-build/attacker/range_proxy.py" "$CORE/home/tc/lab/range_proxy.py"
install -m 0755 "$ROOT/image-build/attacker/exploit.py" "$CORE/home/tc/exploit.py"
install -m 0644 "$ROOT/image-build/attacker/notes.txt" "$CORE/home/tc/notes.txt"
install -m 0644 "$ROOT/image-build/attacker/dillorc" "$CORE/home/tc/.dillo/dillorc"
install -m 0755 "$ROOT/image-build/attacker/x-range.sh" "$CORE/home/tc/.X.d/50-range"
cat >>"$CORE/home/tc/.profile" <<'EOF'
export http_proxy=http://127.0.0.1:8080/
export HTTP_PROXY=http://127.0.0.1:8080/
export no_proxy=
export NO_PROXY=
EOF
# Serial is a real guest shell, used for network checks and optional console UI.
sed -i '/ttyS0/d' "$CORE/etc/inittab"
echo 'ttyS0::respawn:/sbin/getty -n -l /usr/local/bin/lab-console 115200 ttyS0 vt100' >>"$CORE/etc/inittab"
chown -R 1000:50 "$CORE/home/tc" 2>/dev/null || true
chmod 0755 "$CORE/home/tc/.X.d/50-range"

mkdir -p "$ISO/cde/optional"
cp -a "$DOWNLOADS/tinycore-packages/"*.tcz "$ISO/cde/optional/"
for dep in "$DOWNLOADS/tinycore-packages/"*.dep; do
  [[ -e "$dep" ]] && cp -a "$dep" "$ISO/cde/optional/"
done
cat "$DOWNLOADS/tinycore-packages/onboot-packages.lst" >>"$ISO/cde/onboot.lst"
# Keep list ordering stable and remove duplicates without dropping base packages.
awk 'NF && !seen[$0]++' "$ISO/cde/onboot.lst" >"$ISO/cde/onboot.lst.new"
mv "$ISO/cde/onboot.lst.new" "$ISO/cde/onboot.lst"

(
  cd "$CORE"
  find . -print0
) | docker run --rm -i --platform linux/amd64 -v "$WORK:/work" alpine:3.22.1 sh -c '
  apk add --no-cache cpio gzip >/dev/null
  cd /work/core && cpio --null -o -H newc | gzip -9 > /work/core.gz
'
cp "$WORK/core.gz" "$ISO/boot/core.gz"
find "$ISO" -name 'isolinux.cfg' -o -name 'syslinux.cfg' | while read -r cfg; do
  sed -i 's/console=tty0//g; s/console=ttyS0,115200//g' "$cfg"
  sed -i 's/append /append console=tty0 console=ttyS0,115200 /I' "$cfg"
done
isolinux="$(find "$ISO" -name isolinux.bin -print -quit)"
[[ -n "$isolinux" ]] || { echo 'isolinux.bin missing from TinyCore media' >&2; exit 1; }
rel="${isolinux#"$ISO/"}"
bootcat="$(dirname "$rel")/boot.cat"
rm -f "$OUT"
docker run --rm --platform linux/amd64 -v "$ISO:/iso" -v "$(dirname "$OUT"):/output" alpine:3.22.1 sh -c '
  apk add --no-cache xorriso >/dev/null
  xorriso -as mkisofs -R -J -V CYBER_RANGE_ATTACKER -b "'"$rel"'" -c "'"$bootcat"'" -no-emul-boot -boot-load-size 4 -boot-info-table -o /output/attacker-tinycore-11.0.iso /iso >/dev/null
'
[[ -s "$OUT" ]] || { echo 'No attacker ISO produced' >&2; exit 1; }
sha256sum "$OUT"
ls -lh "$OUT"
# Keep the checksummed ISO and downloads, not the extracted remaster tree.
rm -rf "$WORK"
