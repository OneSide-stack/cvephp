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
# Only the ISO tree and the specific core paths edited by the host are handed
# over. Recursively chowning the core would change bin/busybox.suid away from
# root and break login/su inside the guest. All other base UID/GID/mode metadata
# remains exactly as shipped by TinyCore.
docker run --rm --platform linux/amd64 \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  -v "$WORK:/work" alpine:3.22.1 \
  sh -eu -c '
    chown -R "$HOST_UID:$HOST_GID" /work/iso
    chmod -R u+rwX /work/iso
    mkdir -p /work/core/opt /work/core/usr/local/bin /work/core/home/tc
    chown "$HOST_UID:$HOST_GID" /work/core/etc /work/core/etc/inittab /work/core/opt /work/core/usr/local/bin /work/core/home
    chown -R "$HOST_UID:$HOST_GID" /work/core/home/tc
    if [ -e /work/core/opt/bootlocal.sh ]; then chown "$HOST_UID:$HOST_GID" /work/core/opt/bootlocal.sh; fi
    chmod u+rwX /work/core/etc /work/core/etc/inittab /work/core/opt /work/core/usr/local/bin /work/core/home
    chmod -R u+rwX /work/core/home/tc
    if [ -e /work/core/opt/bootlocal.sh ]; then chmod u+rwX /work/core/opt/bootlocal.sh; fi
  '

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
# A pre-created home profile prevents Tiny Core's setupHome from copying its
# stock profile. Preserve the stock desktop startup explicitly, with proxy
# variables first, and restrict startx to tty1 so ttyS0 cannot race the GUI.
cat >"$CORE/home/tc/.profile" <<'EOF'
export http_proxy=http://127.0.0.1:8080/
export HTTP_PROXY=http://127.0.0.1:8080/
export no_proxy=
export NO_PROXY=
EOF
cat "$CORE/etc/skel/.profile" >>"$CORE/home/tc/.profile"
sed -i 's|\[ ${TERMTYPE:5:3} == "tty" \]|[ "$TERMTYPE" = "/dev/tty1" ]|' "$CORE/home/tc/.profile"
grep -F '[ "$TERMTYPE" = "/dev/tty1" ]' "$CORE/home/tc/.profile" >/dev/null
sed -i 's|^startx$|startx >/tmp/cyber-range-x.log 2>\&1|' "$CORE/home/tc/.profile"
grep -F 'startx >/tmp/cyber-range-x.log 2>&1' "$CORE/home/tc/.profile" >/dev/null
# Serial is a real guest shell, used for network checks and optional console UI.
sed -i '/ttyS0/d' "$CORE/etc/inittab"
echo 'ttyS0::respawn:/sbin/getty -n -l /usr/local/bin/lab-console 115200 ttyS0 vt100' >>"$CORE/etc/inittab"
chmod 0755 "$CORE/home/tc/.X.d/50-range"

# Restore the handful of edited base paths and assign TinyCore's documented
# tc account (uid 1001, group staff/50) to its home. Fail before packaging if
# the root-owned setuid launcher was not preserved.
docker run --rm --platform linux/amd64 -v "$WORK:/work" alpine:3.22.1 sh -eu -c '
  chown 0:0 /work/core/etc /work/core/usr/local/bin \
    /work/core/usr/local/bin/labctl /work/core/usr/local/bin/lab-console
  chown 0:50 /work/core/etc/inittab /work/core/home /work/core/opt /work/core/opt/bootlocal.sh
  chown -R 1001:50 /work/core/home/tc
  chmod 0755 /work/core/etc /work/core/opt/bootlocal.sh \
    /work/core/usr/local/bin/labctl /work/core/usr/local/bin/lab-console
  chmod 0664 /work/core/etc/inittab
  chmod 0775 /work/core/home /work/core/usr/local/bin
  chmod 2775 /work/core/opt
  test "$(stat -c %u /work/core/bin/busybox.suid)" = 0
  test "$(stat -c %a /work/core/bin/busybox.suid)" = 4755
  test "$(stat -c %u /work/core/home/tc)" = 1001
'

mkdir -p "$ISO/cde/optional"
cp -a "$DOWNLOADS/tinycore-packages/"*.tcz "$ISO/cde/optional/"
for dep in "$DOWNLOADS/tinycore-packages/"*.dep; do
  [[ -e "$dep" ]] && cp -a "$dep" "$ISO/cde/optional/"
done
cat "$DOWNLOADS/tinycore-packages/onboot-packages.lst" >>"$ISO/cde/onboot.lst"
# Keep list ordering stable and remove duplicates without dropping base packages.
awk 'NF && !seen[$0]++' "$ISO/cde/onboot.lst" >"$ISO/cde/onboot.lst.new"
mv "$ISO/cde/onboot.lst.new" "$ISO/cde/onboot.lst"

docker run --rm --platform linux/amd64 -v "$WORK:/work" alpine:3.22.1 sh -eu -c '
  apk add --no-cache cpio gzip >/dev/null
  cd /work/core
  find . -print0 > /work/core-files.bin
  cpio --null -o -H newc < /work/core-files.bin > /work/core.cpio
  gzip -9 -c /work/core.cpio > /work/core.gz
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
docker run --rm --platform linux/amd64 -v "$WORK:/work" alpine:3.22.1 \
  sh -c 'rm -rf /work/core /work/iso /work/core.cpio /work/core.gz /work/core-files.bin'
rm -rf "$WORK"
